const core = require("@actions/core");

const getAppStats = require("./lib/app-stats");

main();

async function main() {
  const id = core.getInput("id", { required: true });
  const privateKey = core
    .getInput("private_key", { required: true })
    .replace(/\\n/g, "\n");

  try {
    const {
      installations,
      popularRepositories,
      suspendedInstallations,
    } = await getAppStats({
      id,
      privateKey,
    });
    core.setOutput("installations", installations);
    core.setOutput("popular_repositories", JSON.stringify(popularRepositories));
    core.setOutput("suspended_installations", suspendedInstallations);
    console.log("done.");
  } catch (error) {
    core.error(error);
    core.setFailed(error.message);
  }
}
