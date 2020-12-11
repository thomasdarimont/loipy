import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="loipy",
    version="0.0.1",
    author="Daniel Fett",
    author_email="danielf@yes.com",
    description="LOIPY: Legacy OpenID Connect Integration Proxy for yes®",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yescom/loipy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "flask",
        "flask_redis",
        "pyop",
        "pyyes @ git+https://github.com/yescom/pyyes@main#egg=pyyes",
        "pyyaml",
    ],
)
