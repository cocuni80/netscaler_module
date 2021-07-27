import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

INSTALL_REQUIRES = ['requests']

setuptools.setup(
    name="netscaler_module",
    version="0.1",
    author="Jorge Riveros",
    author_email="christian.riveros@outlook.com",
    license='MIT',
    description='A Python package to query Netscaler Information',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cocuni80/netscaler_module",
    packages=['module'],
    install_requires=INSTALL_REQUIRES,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.x',
)
