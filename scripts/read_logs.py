# scripts/read_Logs.py

with open('data/auth_sample.log', 'r', encoding = 'utf-8') as file:
    content = file.read()
    print('Contenido del archivo:\n', content)

