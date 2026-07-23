import re
import glob

pattern = re.compile(r"url_for\('static',\s*filename='([^']+\.css)'\)")

def replacement(m):
    return f"url_for('static', filename='{m.group(1)}') + '?v=' + css_version"

for fpath in glob.glob('templates/*.html'):
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = pattern.sub(replacement, content)
    if new_content != content:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f'Updated: {fpath}')
    else:
        print(f'No change: {fpath}')

print('Done.')
