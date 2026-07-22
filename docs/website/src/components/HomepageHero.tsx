import React, { FC } from "react";
import Link from "@docusaurus/Link";
import { forTablet } from "../../helpers/media-queries";
import { motion } from "framer-motion";
import { hero } from "../../homepage-content/hero";

const HomepageHero: FC = () => {
  return (
    <div className="relative bg-cover bg-[url(/mobile-mithril-hero-thumbnail.jpg)] tablet:bg-[url(/desktop-mithril-hero-thumbnail.jpg)] bg-secondary z-20 -mt-(--ifm-navbar-height) pt-(--ifm-navbar-height)">
      <video
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        onPlaying={(e) => {
          (e.target as HTMLVideoElement).style.opacity = "1";
        }}
        aria-label="Video background"
        className="absolute top-0 left-0 right-0 bottom-0 object-cover -z-10 w-full h-full opacity-0 transition-opacity"
      >
        <source
          src={"desktop-mithril-hero-original.mp4"}
          type="video/mp4"
          media={forTablet}
          data-testid="video-background-source-wide"
        />
        <source
          src={"mobile-mithril-hero-original.mp4"}
          type="video/mp4"
          data-testid="video-background-source-narrow"
        />
      </video>
      <div className="pageContainer pb-16 tablet:pb-40 pt-10 tablet:pt-[11.438rem]">
        <div className="component-lg">
          <div className="tablet:pb-6 pb-10 tablet:max-w-[544px] text-primary">
            <motion.h1
              className="hero-title tablet:pb-6 pb-10"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ ease: "easeInOut", duration: 0.75, delay: 0.4 }}
            >
              {hero.title}
            </motion.h1>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ ease: "easeInOut", duration: 0.75, delay: 1 }}
              className="text-xl leading-8"
            >
              {hero.standfirst}
            </motion.p>
          </div>
          <motion.div
            className="flex justify-center tablet:justify-start"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ ease: "easeInOut", duration: 0.75, delay: 1.2 }}
          >
            <Link
              className="inline-block px-6 py-4 font-bold text-base text-white rounded-lg border-[0.5px] border-gray-border no-underline bg-secondary hover:no-underline hover:scale-105 transition-all hover:text-white"
              to="/manual/operate/run-signer-node"
            >
              Run a signer node
            </Link>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default HomepageHero;
