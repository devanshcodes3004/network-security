'''
the setup.py file is an essentail part of any Python package. It contains metadata about the package, such as its name, version, author, and dependencies. This information is used by tools like pip to install the package and manage its dependencies.
In the context of a package like "networksecurity.utils", the setup.py file would typically include information about the package's name, version, author, description, and any dependencies it has on other packages. This allows users to easily install the package and its dependencies using pip.

'''


from setuptools import setup, find_packages
from typing import List


def get_requirements() -> List[str]:
    '''
    this dunction will return list of requirements
    '''

    requirments_list=[]

    try:
        with open("requirements.txt", "r") as file:

            lines=file.readlines()

            for line in lines:
                requirment=line.strip()

                if requirment and requirment!="-e .":
                    requirments_list.append(requirment)

    except Exception as e:
        print(f"Error occurred while reading requirements: {e}")

    return requirments_list


setup(
    name="networksecurity",
    version="0.1.0",
    author="devansh",
    author_email="devanshcodes3004@gmail.com",
    packages=find_packages(),
    install_requires=get_requirements()
)