from setuptools import setup, find_packages
import os

setup(
    name="lazyframework",
    version="1.0.0",
    author="LazyFramework Team",
    author_email="team@lazyframework.id",
    description="Advanced Penetration Testing Framework with GUI & CLI",
    long_description=open("README.md", encoding="utf-8").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/breachcipher/Lazy-Framework",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "PyQt6",
        "rich",
        "prompt_toolkit",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "lzf = bin.console:LazyFramework.repl",   # CLI
            "lazyframework = gui:run_gui",            # GUI
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    package_data={
        "": ["*.json", "*.sh", "*.desktop"],
    },
)
