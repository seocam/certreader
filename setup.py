import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certreader",
    version="0.1.0",
    author="Sergio Oliveira Campos",
    author_email="seocam@redhat.com",
    description="Yet another x509 certificate parser.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seocam/certreader",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "certreader2yaml = certreader.cli:to_yaml",
            "certreader2json = certreader.cli:to_json",
        ],
    },
    include_package_data=True,
    package_data={
        "certreader": ["data/*.yml"],
    },
    install_requires=[
        "cryptography",
        "pyasn1",
        "pyyaml",
    ]
)
