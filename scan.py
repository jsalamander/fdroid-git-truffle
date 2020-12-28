import datetime
import hashlib
import os
import shutil
import tempfile
from multiprocessing import Pool
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch
from git import NULL_TREE, Repo
from tqdm import tqdm
from truffleHog.truffleHog import clone_git_repo, handle_results, path_included, find_entropy, regex_check

es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


def clean_up(output):
    issues_path = output.get("issues_path", None)
    if issues_path and os.path.isdir(issues_path):
        shutil.rmtree(output["issues_path"])


def diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes, do_regex,
                printJson, path_inclusions, path_exclusions):
    issues = []
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files"):
            continue
        if not path_included(blob, path_inclusions, path_exclusions):
            continue
        commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        foundIssues = []
        entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash)
        if entropicDiff:
            foundIssues.append(entropicDiff)
        found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash,
                                    custom_regexes)
        foundIssues += found_regexes
        issues += foundIssues
    return issues


def find_strings(git_url, since_commit=None, max_depth=1000000, printJson=False, do_regex=True, do_entropy=True,
                 surpress_output=False,
                 custom_regexes={}, branch=None, repo_path=None, path_inclusions=None, path_exclusions=None):
    output = {"foundIssues": []}
    if repo_path:
        project_path = repo_path
    else:
        project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    if branch:
        branches = repo.remotes.origin.fetch(branch)
    else:
        branches = repo.remotes.origin.fetch()
    printable = []
    for remote_branch in branches:
        since_commit_reached = False
        branch_name = remote_branch.name
        prev_commit = None
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
            if not prev_commit:
                prev_commit = curr_commit
                continue
            elif diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            # avoid searching the same diffs
            already_searched.add(diff_hash)
            foundIssues = diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes,
                                      do_regex, surpress_output, path_inclusions,
                                      path_exclusions)
            if len(foundIssues) > 0:
                printable.append(foundIssues)
            prev_commit = curr_commit
        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        foundIssues = diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes,
                                  do_regex, surpress_output, path_inclusions, path_exclusions)
        if len(foundIssues) > 0:
            printable.append(foundIssues)
    output["project_path"] = project_path
    output["clone_uri"] = git_url
    output["issues_path"] = output_dir
    output["findings"] = printable
    output["createdAt"] = datetime.time().isoformat()
    clean_up(output)
    return output


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

                json_results = {}
                try:
                    json_results = find_strings(repo_link)
                except:
                    print("Error on " + repo_link)

                if json_results:
                    try:
                        es.index(index='fdroid-secrets', doc_type='secrets', body=json_results)
                    except:
                        print("unable to store in the es server")


pathlist = Path("./fdroiddata/metadata").rglob('*.yml')
arguments = []
for path in pathlist:
    # because path is object not string
    path_in_str = str(path)
    arguments.append(path_in_str)

with Pool(processes=4, maxtasksperchild=1) as p:
    with tqdm(total=len(arguments)) as pbar:
        for i, _ in enumerate(p.imap_unordered(run_trufflehog, arguments)):
            pbar.update()
