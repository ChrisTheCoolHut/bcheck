import setuptools


setuptools.setup(
     name='conc_check',  
     version='2.0',
     scripts=['bin/c_check.py'] ,
     author="Christoppher Roberts",
     author_email="",
     description="Printf and Command injection testing tool",
     url="https://github.com/ChrisTheCoolHut/Not_a_repo_yet",
     packages=["conc_check"],
     install_package_data=True,
     install_requires=[
     "angr",
     "tox",
     "tqdm",
     ],

 )
