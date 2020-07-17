module.exports = octokitPluginStdoutProgress;

function octokitPluginStdoutProgress(octokit) {
  octokit.hook.before("request", () => process.stdout.write("."));
}
