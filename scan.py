import subprocess
from multiprocessing import Pool
from pathlib import Path

import yaml
from tqdm import tqdm

log = open('trufflehog_results.json', 'a')


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
                subprocess.call(['trufflehog --json ' + repo_link], shell=True, stdout=log)


pathlist = Path("./fdroiddata/metadata").rglob('*.yml')
arguments = []
for path in pathlist:
    # because path is object not string
    path_in_str = str(path)
    arguments.append(path_in_str)

with Pool(50) as p:
    with tqdm(total=len(arguments)) as pbar:
        for i, _ in enumerate(p.imap_unordered(run_trufflehog, arguments)):
            pbar.update()
