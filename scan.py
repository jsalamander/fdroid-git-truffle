import subprocess
from multiprocessing import Pool
from pathlib import Path
from elasticsearch import Elasticsearch
import yaml
from tqdm import tqdm

es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


def run_trufflehog(filepath):
    with open(filepath) as file:
        fdroid_meta = yaml.load(file, Loader=yaml.FullLoader)
        if "RepoType" in fdroid_meta.keys() and fdroid_meta["RepoType"] == "git":
            if "Repo" in fdroid_meta.keys():
                repo_link = fdroid_meta["Repo"]
                if ".git" not in repo_link:
                    if repo_link.endswith("/"):
                        repo_link = repo_link[:-1]
                    repo_link = repo_link + ".git"

                json_results = ""
                try:
                    process = subprocess.run('trufflehog --json --cleanup ' + repo_link, shell=True)
                    json_results = process.stdout
                except ValueError as err:
                    print("Error on " + repo_link + str(err))

                if not json_results:
                    es.index(index='fdroid-secrets', doc_type='secrets', body=json_results)


pathlist = Path("./fdroiddata/metadata").rglob('*.yml')
arguments = []
for path in pathlist:
    # because path is object not string
    path_in_str = str(path)
    arguments.append(path_in_str)

with Pool(16) as p:
    with tqdm(total=len(arguments)) as pbar:
        for i, _ in enumerate(p.imap_unordered(run_trufflehog, arguments)):
            pbar.update()
