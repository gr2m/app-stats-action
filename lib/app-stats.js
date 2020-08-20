module.exports = getAppStats;

const Octokit = require("./app-octokit");

async function getAppStats({ id, privateKey }) {
  try {
    const octokit = new Octokit({
      auth: {
        id,
        privateKey,
      },
    });

    const installations = await octokit.paginate(
      "GET /app/installations",
      {
        mediaType: { previews: ["machine-man"] },
        per_page: 100,
      },
      (response) =>
        response.data.map((installation) => {
          const {
            id,
            account: { login },
            suspended_at,
          } = installation;

          return { id, login, suspended: !!suspended_at };
        })
    );

    const accounts = [];
    let installedRepositories = 0;
    let suspendedInstallations = 0;
    for (const installation of installations) {
      if (installation.suspended) {
        suspendedInstallations++;
        continue;
      }

      const installationOctokit = new Octokit({
        auth: {
          id,
          privateKey,
          installationId: installation.id,
        },
      });

      const repositories = await installationOctokit.paginate(
        "GET /installation/repositories",
        {
          mediaType: { previews: ["machine-man"] },
          per_page: 100,
        },
        (response) =>
          response.data.map((repository) => {
            return {
              private: repository.private,
              stars: repository.stargazers_count,
            };
          })
      );

      const stars = repositories
        .filter((repository) => !repository.private)
        .reduce((stars, repository) => {
          return stars + repository.stars;
        }, 0);

      accounts.push({ ...installation, stars });
      installedRepositories += repositories.length;
    }

    console.log("");
    return {
      installations: accounts.length + suspendedInstallations,
      repositories: installedRepositories,
      suspendedInstallations,
      popularRepositories: accounts
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 10)
        .map(({ suspended, ...account }) => account),
    };
  } catch (error) {
    console.log(error);
    throw error;
  }
}
