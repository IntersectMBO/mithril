/* 
Code from marutpun on May 11
https://github.com/facebook/docusaurus/discussions/11741
*/

import type { Plugin, PostCssOptions } from "@docusaurus/types";

export default function tailwindCssPlugin(): Plugin | null {
  return {
    name: "tailwindcss-plugin",
    configurePostCss(postcssOptions: PostCssOptions) {
      postcssOptions.plugins.push(require("@tailwindcss/postcss"));
      return postcssOptions;
    },
  };
}
