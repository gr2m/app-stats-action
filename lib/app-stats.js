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
          } = installation;

          return { id, login };
        })
    );

    const accounts = [];
    for (const installation of installations) {
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
    }

    console.log("");
    return {
      installations: accounts.length,
      popularRepositories: accounts
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 10),
    };
  } catch (error) {
    console.log(error);
    throw error;
  }
}
