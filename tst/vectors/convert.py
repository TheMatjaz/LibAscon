d = {
    'PT': '.plaintext',
    'AD': '.assoc_data',
    'Nonce': '.nonce',
    'Key': '.key',
    'CT': '.expected_ciphertext',
    'Count': 'Count',
    '\n': '\n',
}

with open('aead128.txt') as f, open('aead128.c', 'w') as o:
    for line in f:
        try:
            fields = line.split(' = ')
            fields[0] = d[fields[0]]
            bites = bytes.fromhex(fields[1])
            fields[1] = ', '.join(f'0x{b:02X}' for b in bites)
            fields[1] = '{' + fields[1] + '},'
            if fields[0] == '.plaintext':
                fields[1] += f'\n.plaintext_len = {len(bites)},'
            if fields[0] == '.expected_ciphertext':
                fields[1] += f'\n.expected_ciphertext_len = {len(bites)},'
            if fields[0] == '.assoc_data':
                fields[1] += f'\n.assoc_data_len = {len(bites)},'
        except (ValueError, IndexError):
            pass
        o.write(' = '.join(fields))
        o.write('\n')
