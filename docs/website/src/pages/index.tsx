import React from "react";
import Head from "@docusaurus/Head";
import Layout from "@theme/Layout";
import { PageContext, PageType } from "../context/PageContext";
import HomepageHero from "../components/HomepageHero";
import Features from "../components/Features";
import WhyMithril from "../components/WhyMithril";
import Trusted from "../components/Trusted";

export default function HomePage() {
  return (
    <PageContext.Provider value={{ page: PageType.Landing }}>
      <div style={{ zIndex: 1000 }}>
        <Layout description="Mithril is a stake-based threshold multisignature protocol for Cardano, enabling trustless, lightweight access to verified blockchain state without requiring a full node.">
          <Head>
            <title>Mithril | Trustless state proofs for Cardano</title>
          </Head>
          <HomepageHero />
          <main>
            <WhyMithril />
            <Features />
            <Trusted />
          </main>
        </Layout>
      </div>
    </PageContext.Provider>
  );
}
