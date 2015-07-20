#! /usr/bin/env python

import argparse
import copy
import json
import os
import pystache
import re
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile

def description_to_id(description):
    pattern = re.compile(r'^[*]*([^.:*]*).*\(.*\)')
    matches = [pattern.match(s) for s in description.split(' ')]
    return '_'.join([m.group(1) for m in matches if m])

def is_bss(description):
    sections = description.split(' ')
    pattern = re.compile(r'.*\((.bss|COMMON).*\)')
    return all(pattern.match(s) for s in sections)

def render_linker_script(policy, platform, policy_len):
    states = policy['states']
    templates_dir = os.path.join(os.path.dirname(sys.argv[0]), 'templates')
    renderer = pystache.Renderer(search_dirs=[templates_dir])

    # Split up sections from all states so they end up in the right segment
    data = {
        'policy_len': policy_len,
        'text_sections': [{ 'name': state['name'], 'sections': [{ 'description': section['description'] }
            for section in state['sections'] if section['permissions'] == 'rx'] } for state in states],
        'rodata_sections': [{ 'name': state['name'], 'sections': [{ 'description': section['description'] }
            for section in state['sections'] if section['permissions'] == 'r'] } for state in states],
        'data_sections': [{ 'name': state['name'], 'sections': [{ 'description': section['description'] }
            for section in state['sections'] if section['permissions'] == 'rw' and \
                    not is_bss(section['description'])] } for state in states],
        'bss_sections': [{ 'name': state['name'], 'sections': [{ 'description': section['description'] }
            for section in state['sections'] if section['permissions'] == 'rw' and \
                    is_bss(section['description'])] } for state in states],
        # Hacks, see https://github.com/defunkt/pystache/issues/158
        'description_to_id': lambda s: description_to_id(copy.deepcopy(renderer).render(s, renderer.context))
    }

    return renderer.render_name(platform, data)

def stable_unique(l):
    seen = set()
    return [x for x in l if not (x in seen or seen.add(x))]

# TODO: 32 vs 64bit ELF, changes here are trivial but thought needs to go into
# whats happening in the kernel
def generate_binary_policy(policy, symbol_table, must_resolve=True):
    STATE = 1
    SECTION = 2
    TRANSITION = 3

    chunks = []
    states = policy['states']
    transitions = policy['transitions']
    state_names = [s['name'] for s in states]
    stack_names = stable_unique([s['stack'] for s in states])

    # Pack states
    for state in states:
        stack_id = stack_names.index(state['stack'])
        chunks.append(struct.pack('<II', STATE, stack_id))

        for section in state['sections']:
            start_symbol = '__%s_%s_start' % (state['name'], description_to_id(section['description']))
            end_symbol = '__%s_%s_end' % (state['name'], description_to_id(section['description']))

            start_addr = symbol_table.get(start_symbol, 0)
            end_addr = symbol_table.get(end_symbol, 0)
            if must_resolve and start_addr == 0:
                raise KeyError('Error resolving symbol %s' % start_symbol)
            if must_resolve and end_addr == 0:
                raise KeyError('Error resolving symbol %s' % end_symbol)

            size = end_addr - start_addr

            permissions = 0
            permissions |= (0x4 if 'r' in section['permissions'] else 0)
            permissions |= (0x2 if 'w' in section['permissions'] else 0)
            permissions |= (0x1 if 'x' in section['permissions'] else 0)

            chunks.append(struct.pack('<IIII', SECTION, start_addr, size, permissions))

    # Pack transitions
    for transition in transitions:
        from_state = state_names.index(transition['from'])
        to_state = state_names.index(transition['to'])
        param_size = int(transition['param_size'])
        return_size = int(transition['return_size'])

        trigger_symbol = transition['trigger']

        trigger_addr  = symbol_table.get(trigger_symbol, 0)
        if must_resolve and trigger_addr == 0:
            raise KeyError('Error resolving symbol %s' % trigger_symbol)

        chunks.append(struct.pack('<IIIIII', TRANSITION, from_state, to_state,
            trigger_addr, param_size, return_size))

    return b''.join(chunks)

def parse_link_map(link_map):
    # FIXME: This is somewhat janky, elftools symbol parsing is broken ATM
    # though, so fix later
    pattern = re.compile(r'^[ ]{16}0x[0-9a-f]+[ ]{16}[a-zA-Z0-9_."]\S*')
    lines = link_map.splitlines()
    matches = [line.split()[:2] for line in lines if pattern.match(line)]
    return { name : int(addr, 16) for (addr, name) in matches }

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='Link a JSON ELFbac policy into a program')
    parser.add_argument('-p', '--policy', metavar='POLICY', required=True,
            help='The JSON ELFbac policy to link into a program')
    parser.add_argument('-l', '--linker', metavar='LINKER', default='ld',
            help='The linker to invoke to link the program')
    parser.add_argument('-c', '--use-compiler', action='store_true',
            help='If specified, using the C compiler driver to link the program, so modify '
                'altered arguments appropriately')
    parser.add_argument('linker_args', metavar='LINKER ARGS', nargs=argparse.REMAINDER)

    args = parser.parse_args(argv[1:])

    with open(args.policy, 'r') as f:
        policy = json.load(f)

    # Try to scout out the linker output file
    output_file = 'a.out'
    for i in xrange(len(args.linker_args) - 1):
        if args.linker_args[i] == '-o' or args.linker_args[i] == '--output':
            output_file = args.linker_args[i + 1]

    policy_len = len(generate_binary_policy(policy, {}, False))
    linker_script = render_linker_script(policy, 'elf32-littlearm', policy_len)

    with tempfile.NamedTemporaryFile('w') as f:
        if args.linker_args[0] == '--':
            args.linker_args = args.linker_args[1:]

        f.write(linker_script)
        f.flush()

        cmd = [args.linker] + args.linker_args + \
                ['-Wl,' + arg if args.use_compiler else arg for arg in ['-M', '-T', f.name]]
        link_map = subprocess.check_output(cmd)
        symbol_map = parse_link_map(link_map)

    # TODO: make sure our heuristic for finding this doesn't clobber something
    if os.path.exists(output_file):
        with open(output_file, 'rb') as f:
            contents = f.read()
            f.seek(0, 0)
            ef = ELFFile(f)
            elfbac_section = ef.get_section_by_name('.elfbac')

        assert(elfbac_section['sh_size'] == policy_len)
        offset = elfbac_section['sh_offset']
        binary_pol = generate_binary_policy(policy, symbol_map)

        new_contents = contents[:offset] + binary_pol + contents[offset + policy_len:]
            
        with open(output_file, 'wb') as f:
            f.write(new_contents)

    return 0

if __name__ == '__main__':
    sys.exit(main())

