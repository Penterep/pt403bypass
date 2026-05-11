import setuptools
from pt403bypass._version import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="pt403bypass",
    version=__version__,
    description="Tool for testing 401/403 authorization bypass techniques",
    author="Penterep",
    author_email="info@penterep.com",
    url="https://www.penterep.com/",
    license="GPLv3",
    packages=setuptools.find_packages(),
    package_data={"pt403bypass": ["templates/*.txt"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ],
    python_requires='>=3.12',
    install_requires=["ptlibs>=1.0.37,<2"],
    entry_points={'console_scripts': ['pt403bypass = pt403bypass.pt403bypass:main']},
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
    project_urls={
        "homepage": "https://www.penterep.com/",
        "repository": "https://github.com/penterep/pt403bypass",
        "tracker": "https://github.com/penterep/pt403bypass/issues",
    }
)
