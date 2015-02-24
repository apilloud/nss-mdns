from buildbot.steps.shell import ShellCommand

# Return true if the build request came from a pull
def is_pull(BuildStep):
    if BuildStep.getProperty('gh_pull_no'):
        return False
    return True

bootstrap = ShellCommand(
        command = ['./bootstrap.sh'],
        alwaysRun = True,
        description = "Bootstrap",
        descriptionDone = "Bootstraped",
        descriptionSuffix = "build")

run = ShellCommand(
        command = ['make'],
        alwaysRun = True,
        timeout = None,
        maxTime = 900,
        description = "Running", descriptionDone = "Ran", descriptionSuffix = "build")

# Steps imported into build
steps = [
        bootstrap,
        run,
]
