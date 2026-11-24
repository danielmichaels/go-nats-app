import shutil
import textwrap
from pathlib import Path

ROOT = Path.cwd()
FRONTEND = "{{ cookiecutter.frontend }}"

REMOVE = {
    "datastar": ["web", "internal/spa"],
    "react": ["internal/htmlui"],
}


def remove_unused_frontend():
    for rel in REMOVE[FRONTEND]:
        path = ROOT / rel
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def create_env():
    shutil.copyfile(ROOT / ".env.sample", ROOT / ".env")


def print_final_instructions():
    steps = {
        "datastar": "task dev",
        "react": "task web:install && task dev",
    }[FRONTEND]
    print(textwrap.dedent(f"""
    Your project `{{ cookiecutter.project_name.strip() }}` is ready ({FRONTEND} frontend).

        cd {{ cookiecutter.project_slug }}
        git init
        go mod tidy
        {steps}

    The first start prints a one-time setup token. Open /setup and create the
    first admin with it.
    """))


remove_unused_frontend()
create_env()
print_final_instructions()
