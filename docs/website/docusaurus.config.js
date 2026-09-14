// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require("prism-react-renderer").themes.github;
const darkCodeTheme = require("prism-react-renderer").themes.dracula;

import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "Mithril",
  tagline:
    "Trustless, lightweight access to verified Cardano blockchain state — no full node required.",
  url: "https://mithril.network",
  baseUrl: "/doc/",
  onBrokenLinks: "throw",
  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: "warn",
    },
  },
  favicon: "img/mithril-logo.svg",
  organizationName: "Input Output Global",
  projectName: "Mithril",

  future: {
    v4: {
      removeLegacyPostBuildHeadAttribute: true,
      useCssCascadeLayers: true,
      siteStorageNamespacing: true,
      fasterByDefault: false,
      mdx1CompatDisabledByDefault: true,
    },
  },

  scripts: [],

  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: "root",
          routeBasePath: "/",
          sidebarPath: require.resolve("./sidebars.js"),
          editUrl: ({ docPath }) => {
            // We want users to submit doc updates to the upstream/next version!
            // Otherwise we risk losing the update on the next release.
            return `https://github.com/IntersectMBO/mithril/edit/main/docs/website/root/${docPath}`;
          },
          lastVersion: "maintained",
          versions: {
            current: {
              label: "Next 🚧",
              banner: "unreleased",
            },
            maintained: {
              label: "Current",
            },
          },
          remarkPlugins: [remarkMath],
          rehypePlugins: [rehypeKatex],
        },
        blog: {
          path: "blog/",
          routeBasePath: "dev-blog",
          blogTitle: "Dev blog",
          blogSidebarTitle: "Dev blog",
          sortPosts: "descending",
          showReadingTime: true,
        },
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
        gtag: {
          trackingID: "G-4MB41WL2Z2",
          anonymizeIP: true,
        },
      }),
    ],
    [
      "redocusaurus",
      {
        specs: [
          {
            spec: "../../openapi.yaml",
            route: "/aggregator-api/next",
          },
          {
            spec: "openapi.current.yaml",
            route: "/aggregator-api/current",
          },
        ],
        theme: {
          primaryColor: "#1890ff",
        },
      },
    ],
  ],

  plugins: [
    "./src/plugins/plugin-tailwind.ts",
    [
      "@docusaurus/plugin-content-blog",
      {
        id: "adr_blog",
        path: "adr",
        routeBasePath: "adr/",
        blogTitle: "ADR",
        blogSidebarTitle: "ADR",
        sortPosts: "descending",
      },
    ],
    [
      "@docusaurus/plugin-client-redirects",
      {
        redirects: [
          {
            to: "/manual/develop/protocol-simulation",
            from: ["/mithril/mithril-protocol/simulation"],
          },
          {
            to: "/manual/operate/become-mithril-spo",
            from: ["/manual/getting-started/SPO-on-boarding-guide"],
          },
          {
            to: "/manual/operate/run-signer-node",
            from: ["/manual/getting-started/run-signer-node"],
          },
          {
            to: "/manual/develop/",
            from: ["/category/developer-docs"],
          },
          {
            to: "/manual/develop/nodes/mithril-aggregator",
            from: ["/manual/developer-docs/nodes/mithril-aggregator"],
          },
          {
            to: "/manual/develop/nodes/mithril-signer",
            from: ["/manual/developer-docs/nodes/mithril-signer"],
          },
          {
            to: "/manual/develop/nodes/mithril-client",
            from: ["/manual/developer-docs/nodes/mithril-client"],
          },
          {
            to: "/manual/develop/nodes/mithril-client-library",
            from: ["/manual/developer-docs/nodes/mithril-client-library"],
          },
          {
            to: "/manual/develop/nodes/mithril-client-library-wasm",
            from: ["/manual/developer-docs/nodes/mithril-client-library-wasm"],
          },
          {
            to: "/manual/develop/references",
            from: ["/manual/developer-docs/references"],
          },
          {
            to: "/mithril/advanced/mithril-protocol",
            from: ["/category/mithril-protocol"],
          },
          {
            to: "/mithril/advanced/mithril-protocol/protocol",
            from: ["/mithril/mithril-protocol/protocol"],
          },
          {
            to: "/mithril/advanced/mithril-protocol/certificates",
            from: ["/mithril/mithril-protocol/certificates"],
          },
          {
            to: "/mithril/advanced/mithril-protocol/security",
            from: ["/mithril/mithril-protocol/security"],
          },
          {
            to: "/mithril/advanced/mithril-network/",
            from: ["/category/mithril-network"],
          },
          {
            to: "/mithril/advanced/mithril-network/architecture",
            from: ["/mithril/mithril-network/architecture"],
          },
          {
            to: "/mithril/advanced/mithril-network/aggregator",
            from: ["/mithril/mithril-network/aggregator"],
          },
          {
            to: "/mithril/advanced/mithril-network/signer",
            from: ["/mithril/mithril-network/signer"],
          },
          {
            to: "/mithril/advanced/mithril-network/client",
            from: ["/mithril/mithril-network/client"],
          },
          {
            to: "/mithril/advanced/threat-model",
            from: ["/mithril/threat-model"],
          },
          {
            to: "/mithril/advanced/mithril-certification/cardano-node-database",
            from: ["/mithril/advanced/mithril-certification/cardano-node-database-v2"],
          },
          {
            to: "/next/mithril/advanced/mithril-certification/cardano-node-database",
            from: ["/next/mithril/advanced/mithril-certification/cardano-node-database-v2"],
          },
          {
            to: "/aggregator-api/current",
            from: ["/aggregator-api"],
          },
        ],
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      metadata: [{ name: "og:image", content: "https://mithril.network/doc/img/logo.png" }],
      announcementBar: {
        id: "announcement",
        content:
          'SPOs: the Mithril signer node is stable and production-ready. <a rel="noopener noreferrer" href="https://mithril.network/doc/manual/operate/become-mithril-spo">Install it today!</a>',
        backgroundColor: "#2A598E",
        textColor: "#f1f1f1",
        isCloseable: true,
      },
      colorMode: {
        defaultMode: "light",
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },
      navbar: {
        logo: {
          alt: "Mithril. A complete guide.",
          src: "img/mithril-logo-text.svg",
        },
        items: [
          {
            type: "doc",
            docId: "manual/welcome",
            position: "right",
            label: "Manual",
          },
          {
            type: "doc",
            docId: "mithril/intro",
            label: "Protocol",
            position: "right",
          },
          {
            type: "dropdown",
            label: "Use Cases",
            position: "right",
            items: [
              {
                type: "doc",
                docId: "use-cases/wallets/index",
                label: "Wallets",
              },
              {
                type: "doc",
                docId: "use-cases/bridges",
                label: "Bridges",
              },
            ],
          },
          {
            type: "docsVersionDropdown",
            position: "right",
            dropdownActiveClassDisabled: true,
          },
          {
            label: "Explorer",
            to: "https://mithril.network/explorer",
            position: "right",
          },
          {
            label: "Glossary",
            to: "/glossary",
            position: "right",
          },
          {
            label: "Blog",
            to: "/dev-blog",
            position: "right",
          },
          {
            label: "ADRs",
            to: "/adr",
            position: "right",
          },
          {
            href: "https://github.com/IntersectMBO/mithril",
            position: "right",
            html: `<svg width="26" height="24" viewBox="0 0 26 24" xmlns="http://www.w3.org/2000/svg">
                  <path
                    d="M13.241 0C6.45096 0 0.961914 5.49998 0.961914 12.3042C0.961914 17.7432 4.47894 22.3472 9.35798 23.9767C9.96799 24.0991 10.1914 23.7119 10.1914 23.3862C10.1914 23.1009 10.1713 22.1232 10.1713 21.1044C6.75559 21.8379 6.04429 19.6377 6.04429 19.6377C5.49536 18.2117 4.68202 17.8452 4.68202 17.8452C3.56405 17.0914 4.76346 17.0914 4.76346 17.0914C6.00358 17.1729 6.6543 18.3544 6.6543 18.3544C7.75191 20.2284 9.5206 19.6989 10.2321 19.3729C10.3337 18.5784 10.6592 18.0284 11.0048 17.7229C8.28048 17.4377 5.41418 16.3784 5.41418 11.6522C5.41418 10.3077 5.90178 9.20771 6.67441 8.35222C6.55251 8.04672 6.12548 6.78347 6.79656 5.09273C6.79656 5.09273 7.83334 4.76673 10.1711 6.35572C11.1719 6.08639 12.2041 5.94938 13.241 5.94823C14.2777 5.94823 15.3346 6.09097 16.3106 6.35572C18.6486 4.76673 19.6854 5.09273 19.6854 5.09273C20.3564 6.78347 19.9292 8.04672 19.8073 8.35222C20.6002 9.20771 21.0677 10.3077 21.0677 11.6522C21.0677 16.3784 18.2014 17.4172 15.4568 17.7229C15.9042 18.1099 16.2902 18.8432 16.2902 20.0044C16.2902 21.6544 16.2701 22.9787 16.2701 23.3859C16.2701 23.7119 16.4938 24.0991 17.1036 23.9769C21.9826 22.3469 25.4996 17.7432 25.4996 12.3042C25.5198 5.49998 20.0106 0 13.241 0Z"
                    fill="currentColor"
                  />
              </svg>`,
          },
          {
            href: "https://discord.gg/5kaErDKDRq",
            position: "right",
            html: `<svg width="23" height="18" viewBox="0 0 23 18" xmlns="http://www.w3.org/2000/svg">
                  <path
                    d="M19.4778 1.49632C18.0074 0.806713 16.4357 0.286253 14.7879 0C14.7626 0 14.7246 0 14.7119 0.0390345C14.5091 0.403356 14.2809 0.884782 14.1288 1.27513C12.3543 1.00189 10.6051 1.00189 8.8686 1.27513C8.71649 0.884782 8.47566 0.416368 8.27286 0.0390345C8.26019 0.0130115 8.22216 0 8.19681 0C6.54903 0.286253 4.9773 0.793701 3.51965 1.49632C3.50697 1.49632 3.4943 1.50933 3.4943 1.52234C0.50294 6.08938 -0.308275 10.5523 0.0973328 14.9632C0.0973328 14.9892 0.110008 15.0023 0.122683 15.0153C2.08734 16.4986 4.00131 17.3964 5.86457 17.9949C5.88992 17.9949 5.92794 17.9949 5.94062 17.9689C6.38425 17.3443 6.77718 16.6937 7.11941 16.0041C7.14476 15.9651 7.11941 15.9131 7.08139 15.9C6.4603 15.6528 5.86457 15.3536 5.2815 15.0283C5.2308 15.0023 5.2308 14.9372 5.2815 14.8982C5.40826 14.8071 5.52233 14.703 5.63641 14.6119C5.66176 14.5989 5.68711 14.5859 5.71246 14.6119C9.47701 16.3815 13.5584 16.3815 17.2723 14.6119C17.2976 14.6119 17.323 14.6119 17.3483 14.6119C17.4624 14.703 17.5892 14.8071 17.7032 14.8982C17.7413 14.9242 17.7413 15.0023 17.7032 15.0283C17.1328 15.3666 16.5371 15.6658 15.9034 15.9C15.8653 15.9131 15.84 15.9651 15.8653 16.0041C16.2076 16.6937 16.6005 17.3443 17.0441 17.9689C17.0568 17.9949 17.0948 18.0079 17.1202 17.9949C18.9961 17.3964 20.9101 16.4986 22.8747 15.0153C22.8874 15.0023 22.9001 14.9762 22.9001 14.9632C23.3817 9.86271 22.1015 5.4388 19.5031 1.52234C19.5031 1.50933 19.4904 1.49632 19.4778 1.49632ZM7.6898 12.2828C6.5617 12.2828 5.62374 11.2159 5.62374 9.90175C5.62374 8.58759 6.53635 7.52064 7.6898 7.52064C8.84325 7.52064 9.78121 8.6006 9.75586 9.90175C9.75586 11.2159 8.84325 12.2828 7.6898 12.2828ZM15.333 12.2828C14.2049 12.2828 13.2669 11.2159 13.2669 9.90175C13.2669 8.58759 14.1795 7.52064 15.333 7.52064C16.4864 7.52064 17.4244 8.6006 17.399 9.90175C17.399 11.2159 16.4864 12.2828 15.333 12.2828Z"
                    fill="currentColor"
                  />
              </svg>`,
          },
        ],
      },
      footer: {
        style: "dark",
        logo: {
          alt: "Mithril. A complete guide.",
          src: "img/mithril-logo-dark.svg",
          width: 38,
          height: 38,
        },
        links: [
          {
            title: "Contributing",
            items: [
              {
                label: "Contributing guidelines",
                href: "https://github.com/IntersectMBO/mithril/blob/main/CONTRIBUTING.md",
              },
              {
                label: "Architectural Decision Records",
                to: "/adr",
              },
            ],
          },
          {
            title: "Community",
            items: [
              {
                label: "Discord (#general-mithril)",
                href: "https://discord.gg/5kaErDKDRq",
              },
              {
                label: "GitHub discussions",
                href: "https://github.com/IntersectMBO/mithril/discussions",
              },
              {
                label: "Stack Exchange",
                href: "https://cardano.stackexchange.com/search?q=mithril",
              },
            ],
          },
          {
            title: "More",
            items: [
              {
                label: "Mithril networks status",
                href: "https://mithril.cronitorstatus.com/",
              },
              {
                label: "Mithril protocol insights",
                href: "https://lookerstudio.google.com/s/mbL23-8gibI",
              },
              {
                label: "Logbook",
                href: "https://github.com/IntersectMBO/mithril/wiki/Logbook",
              },
              {
                label: "Input Output (Blog)",
                href: "https://iohk.io/en/blog",
              },
            ],
          },
          {
            title: "Legal",
            items: [
              {
                label: "Privacy policy",
                href: "https://static.iohk.io/terms/iog-privacy-policy.pdf",
              },
              {
                label: "Terms and conditions",
                href: "https://static.iohk.io/terms/iog-terms-and-conditions.pdf",
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} IOG, Inc.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: ["rust", "toml", "bash", "powershell"],
      },
      mermaid: {
        theme: { light: "base", dark: "base" },
      },
    }),
  themes: ["@docusaurus/theme-mermaid"],
  stylesheets: [
    {
      href: "https://cdn.jsdelivr.net/npm/katex@0.13.24/dist/katex.min.css",
      type: "text/css",
      integrity: "sha384-odtC+0UGzzFL/6PNoE8rX/SPcQDXBJ+uRepguP4QkPCm2LBxH3FA3y+fKSiJ+AmM",
      crossorigin: "anonymous",
    },
  ],
};

module.exports = config;
