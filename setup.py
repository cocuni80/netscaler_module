import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

INSTALL_REQUIRES = ['nitro-python',
                    'paramiko'
                    ]

setuptools.setup(
    name="netscaler_module",
    version="1.3",
    author="Jorge Riveros",
    author_email="christian.riveros@outlook.com",
    license='MIT',
    description='A Python package to get REST API Netscaler Information',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cocuni80/netscaler_module",
    packages=setuptools.find_packages(),
    install_requires=INSTALL_REQUIRES,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.x',
)
