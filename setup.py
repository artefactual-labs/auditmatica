from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="auditmatica",
    description="Audit Archivematica user activities via nginx access logs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/artefactual-labs/auditmatica",
    author="Artefactual Systems, Inc.",
    author_email="info@artefactual.com",
    license="AGPL 3",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["Click"],
    entry_points="""
        [console_scripts]
        auditmatica=cli.cli:auditmatica
    """,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
