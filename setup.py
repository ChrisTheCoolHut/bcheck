import setuptools


setuptools.setup(
     name='bin_check',  
     version='1.0',
     scripts=['bin/bcheck.py'] ,
     author="Christoppher Roberts",
     author_email="",
     description="Printf and Command injection testing tool",
     url="https://github.com/ChrisTheCoolHut/Not_a_repo_yet",
     packages=["bin_check"],
     install_package_data=True,
     install_requires=[
     "angr",
     "celery",
     "tox",
     "tqdm",
     ],

 )
