import importlib
import os

if __name__ != '__main__':
    for file in os.listdir(os.path.dirname(__file__)):
        full = os.path.join(os.path.dirname(__file__), file)
        if (file.endswith('.py') and file != '__init__.py'):
            importlib.import_module(f'{__name__}.{file[:-3]}')
        elif os.path.isdir(full) and os.path.exists(f"{full}/__init__.py"):
            importlib.import_module(f'{__name__}.{file}')
