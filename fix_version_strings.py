import os
import re

templates_dir = r'd:\Flask website\templates'

# Matches: url_for('static', filename='X.css') + '?v=' + css_version + '?v=' + css_version ...
# (repeated any number of times)
bad_pattern = re.compile(
    r"(url_for\('static',\s*filename='[^']+\.css'\))"
    r"(\s*\+\s*'\?v='\s*\+\s*css_version){2,}"
)

def fix_link(m):
    url_call = m.group(1)
    # Replace with a single clean Jinja expression ending:
    # url_for(...) }}?v={{ css_version
    return url_call + " }}?v={{ css_version "

fixed_files = []
for fname in os.listdir(templates_dir):
    if not fname.endswith('.html'):
        continue
    fpath = os.path.join(templates_dir, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = bad_pattern.sub(fix_link, content)
    if new_content != content:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        fixed_files.append(fname)
        print(f'Fixed: {fname}')
    else:
        print(f'No change: {fname}')

print()
print(f'Total fixed: {len(fixed_files)}')
print('Done.')
