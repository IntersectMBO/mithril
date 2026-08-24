import React, { type ReactNode } from "react";
import clsx from "clsx";
import { ThemeClassNames } from "@docusaurus/theme-common";
import type { Props } from "@theme/Footer/Layout";

export default function FooterLayout({
  style,
  links,
  logo,
  copyright,
}: Props): ReactNode {
  return (
    <footer
      className={clsx(
        ThemeClassNames.layout.footer.container,
        "footer bg-gray-dark",
        {
          "footer--dark": style === "dark",
        },
      )}
    >
      <div className="container container-fluid">
        {links}
        {(logo || copyright) && (
          <div className="flex justify-between items-center border-t border-t-white-ish px-6">
            {logo && <div className="margin-bottom--sm">{logo}</div>}
            {copyright}
          </div>
        )}
      </div>
    </footer>
  );
}
