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

def is_bss(description):
    sections = description.split(' ')
    return all(re.match(r'.*\((.bss|COMMON).*\)', s) for s in sections)

def render_linker_script(policy, platform, policy_len):
    states = policy['states']
    templates_dir = os.path.join(os.path.dirname(sys.argv[0]), 'templates')
    renderer = pystache.Renderer(search_dirs=[templates_dir])

    # Split up sections from all states so they end up in the right segment

    text_sections = []
    rodata_sections = []
    data_sections = []
    bss_sections = []

    for state in states:
        for section in state['sections']:
            if not section.get('create', True):
                continue

            if section['flags'] == 'rx':
                text_sections.append({
                    'description': section['description'],
                    'name': section.get('name', state['name'])
                })

            if section['flags'] == 'r':
                rodata_sections.append({
                    'description': section['description'],
                    'name': section.get('name', state['name'])
                })

            if section['flags'] == 'rw' and not is_bss(section['description']):
                data_sections.append({
                    'description': section['description'],
                    'name': section.get('name', state['name'])
                })

            if section['flags'] == 'rw' and is_bss(section['description']):
                bss_sections.append({
                    'description': section['description'],
                    'name': section.get('name', state['name'])
                })

    data = {
        'policy_len': policy_len,
        'text_sections': text_sections,
        'rodata_sections': rodata_sections,
        'data_sections': data_sections,
        'bss_sections': bss_sections
    }

    return renderer.render_name(platform, data)

def stable_unique(l):
    seen = set()
    return [x for x in l if not (x in seen or seen.add(x))]

def generate_binary_policy(policy, section_map, symbol_map, must_resolve=True, verbose=False):
    STATE = 1
    SECTION = 2
    DATA_TRANSITION = 3
    CALL_TRANSITION = 4

    chunks = []
    states = policy['states']
    data_transitions = policy.get('data_transitions', [])
    call_transitions = policy.get('call_transitions', [])
    state_names = [s['name'] for s in states]
    stack_names = stable_unique([s['stack'] for s in states])

    if verbose:
        print '=' * 80

    # Pack num stacks
    chunks.append(struct.pack('<I', len(stack_names)))

    # Pack states
    for state in states:
        if verbose:
            print 'State %s:' % state['name']

        stack_id = stack_names.index(state['stack'])
        chunks.append(struct.pack('<II', STATE, stack_id))

        for section in state['sections']:
            flags = 0
            flags |= (0x1 if 'r' in section['flags'] else 0)
            flags |= (0x2 if 'w' in section['flags'] else 0)
            flags |= (0x4 if 'x' in section['flags'] else 0)

            name = section.get('name', state['name'])
            if section.get('create', True):
                name = [None, '.rodata.', '.data', '.data.', None, '.text.', None, None][flags] + name
                if section['flags'] == 'rw' and is_bss(section['description']):
                    name = '.bss.' + state['name']

            base, size = section.get('base'), section.get('size')
            if not base or not size:
                base, size = section_map.get(name, (0, 0))

            if verbose:
                print '\t%s: %08x->%08x, %x' % (name, base, base + size, flags)

            chunks.append(struct.pack('<IIII', SECTION, base, size, flags))

    # Pack data transitions
    for transition in data_transitions:
        from_state = state_names.index(transition['from'])
        to_state = state_names.index(transition['to'])
        size = int(transition['size'])

        base_symbol = transition['base']

        if re.match(r'0x[0-9a-f]+', base_symbol):
            base = int(base_symbol, 16)
        else:
            base = symbol_map.get(base_symbol, 0)

        if must_resolve and not base:
            raise KeyError('Error resolving call transition at %s' % base_symbol)

        flags = 0
        flags |= (0x1 if 'r' in transition['flags'] else 0)
        flags |= (0x2 if 'w' in transition ['flags'] else 0)
        flags |= (0x4 if 'x' in transition['flags'] else 0)

        if verbose:
            print 'Data Transition from %s->%s on %08x->%08x, %x' % (from_state, to_state,
                base, base + size, flags)

        chunks.append(struct.pack('<IIIIII', DATA_TRANSITION, from_state, to_state,
            base, size, flags))

    # Pack call transitions
    for transition in call_transitions:
        from_state = state_names.index(transition['from'])
        to_state = state_names.index(transition['to'])
        param_size = int(transition['param_size'])
        return_size = int(transition['return_size'])

        address_symbol = transition['address']

        if re.match(r'0x[0-9a-f]+', address_symbol):
            address = int(address_symbol, 16)
        else:
            address = symbol_map.get(address_symbol, 0)

        if must_resolve and not address:
            raise KeyError('Error resolving data transition at %s' % address_symbol)

        if verbose:
            print 'Call Transition from %08x->%08x on %x,%x,%x' % (from_state, to_state,
                    address, param_size, return_size)

        chunks.append(struct.pack('<IIIIII', CALL_TRANSITION, from_state, to_state,
            address, param_size, return_size))

    if verbose:
        print '=' * 80

    return b''.join(chunks)

def parse_link_map(link_map):
    # Skip until memory map begins
    match = re.search(r'^Linker script and memory map$', link_map, re.MULTILINE)
    if not match:
        return {}
    link_map = link_map[match.end():]

    # Skip discarded sections if possible
    match = re.search(r'^/DISCARD/$', link_map, re.MULTILINE)
    if match:
        link_map = link_map[:match.start()]

    # Find all allocated sections minus our stub policy section and return their
    # addresses and sizes in a map
    sections = re.findall(r'^(\.[a-zA-Z0-9_.]+)\s+(0x[a-f0-9]+)\s+(0x[a-f0-9]+)\s+.*$', link_map, re.MULTILINE)
    section_map = { name: (int(address, 16), int(size, 16)) for (name, address, size) in sections \
            if name != '.elfbac' and int(size, 16) > 0 }

    symbols = re.findall(r'^ {16}(0x[a-f0-9]+)\s+(\w+)$', link_map, re.MULTILINE)
    symbol_map = { name: int(address, 16) for (address, name) in symbols }

    return (section_map, symbol_map)

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='Link a JSON ELFbac policy into a program')
    parser.add_argument('-a', '--arch', metavar='ARCH', default='elf32-littlearm',
            help='The target architecture for linker script generation, default is elf32-littlearm')
    parser.add_argument('-p', '--policy', metavar='POLICY', required=True,
            help='The JSON ELFbac policy to link into a program')
    parser.add_argument('-l', '--linker', metavar='LINKER', default='ld',
            help='The linker to invoke to link the program')
    parser.add_argument('-c', '--use-compiler', action='store_true',
            help='If specified, using the C compiler driver to link the program, so modify '
                'altered arguments appropriately')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='If specified, provide verbose output')
    parser.add_argument('linker_args', metavar='LINKER ARGS', nargs=argparse.REMAINDER)

    args = parser.parse_args(argv[1:])

    with open(args.policy, 'r') as f:
        policy = json.load(f)

    # Try to scout out the linker output file
    output_file = 'a.out'
    for i in xrange(len(args.linker_args) - 1):
        if args.linker_args[i] == '-o' or args.linker_args[i] == '--output':
            output_file = args.linker_args[i + 1]

    policy_len = len(generate_binary_policy(policy, {}, {}, False))
    linker_script = render_linker_script(policy, args.arch, policy_len)
    if args.verbose:
        print linker_script

    with tempfile.NamedTemporaryFile('w') as f:
        if args.linker_args[0] == '--':
            args.linker_args = args.linker_args[1:]

        f.write(linker_script)
        f.flush()

        cmd = [args.linker] + args.linker_args + \
                ['-Wl,' + arg if args.use_compiler else arg for arg in ['-M', '-T', f.name]]
        link_map = subprocess.check_output(cmd)
        section_map, symbol_map = parse_link_map(link_map)

    # TODO: make sure our heuristic for finding this doesn't clobber something
    if os.path.exists(output_file):
        with open(output_file, 'rb') as f:
            contents = f.read()
            f.seek(0, 0)
            ef = ELFFile(f)
            elfbac_section = ef.get_section_by_name('.elfbac')

        assert(elfbac_section['sh_size'] == policy_len)
        offset = elfbac_section['sh_offset']

        binary_pol = generate_binary_policy(policy, section_map, symbol_map, True, args.verbose)
        new_contents = contents[:offset] + binary_pol + contents[offset + policy_len:]
 
        with open(output_file, 'wb') as f:
            f.write(new_contents)

    return 0

if __name__ == '__main__':
    sys.exit(main())

