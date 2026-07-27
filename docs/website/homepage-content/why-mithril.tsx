import React from "react";
import { translate } from "@docusaurus/Translate";

export const WhyMithrilContents = {
  title: translate({
    id: "homepage.whyMithril.title",
    message: "WHY MITHRIL?",
  }),
  descriptionParagraph: {
    id: "homepage.whyMithril.paragraphs",
    message: (
      <div className="flex flex-col gap-6">
        <p className="m-0 leading-normal">
          The Cardano blockchain offers robust security, but starting up a new
          node, syncing it with the network, or exchanging data can be slow and
          resource intensive (24GB of RAM, 150GB (and growing) of storage, and
          over 24 hours for initial synchronization.)
        </p>
        <p className="m-0 leading-normal">
          Mithril was developed for Cardano as part of the Basho development
          phase to support optimization, scalability, and interoperability.
        </p>
      </div>
    ),
  },
  timeline: ["Byron", "Shelley", "Goguen", "Basho", "Voltaire"],
};
