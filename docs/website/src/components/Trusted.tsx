import React from "react";
import { motion } from "framer-motion";

import iog from "../../static/img/iog.png";
import blinklabs from "../../static/img/blinklabs.png";
import cardano from "../../static/img/cardano.png";
import midnight from "../../static/img/midnight.png";
import pogun from "../../static/img/pogun.png";
import txpipe from "../../static/img/txpipe.png";
import teragone from "../../static/img/teragone.png";
import uralabs from "../../static/img/uralabs.png";

const logoPartner: Array<{ src: any; alt: string }> = [
  { src: iog, alt: "Input Output Global" },
  { src: blinklabs, alt: "BlinkLabs" },
  { src: cardano, alt: "Cardano" },
  { src: midnight, alt: "Midnight Network" },
  { src: pogun, alt: "Pogun DeFi" },
  { src: txpipe, alt: "TXPipe" },
  { src: teragone, alt: "Teragone Factory" },
  { src: uralabs, alt: "Ura Labs Finance" },
];

const Trusted = () => {
  return (
    <div className="relative w-full h-[50dvh] bg-white">
      <div className="justify-items-center py-14">
        <h3>Trusted by the Cardano ecosystem</h3>
      </div>
      <div className="max-w-2/4 mx-auto pt-14">
        <div className="flex relative overflow-hidden before:absolute before:left-0 before:top-0 before:z-10 before:h-full before:w-10 before:bg-gradient-to-r before:from-zinc-950 before:to-transparent before:content-[''] after:absolute after:right-0 after:top-0 after:h-full after:w-10 after:bg-gradient-to-l after:from-zinc-950 after:to-transparent after:content-['']">
          <motion.div
            transition={{
              duration: 16,
              ease: "linear",
              repeat: Infinity,
            }}
            initial={{ translateX: 0 }}
            animate={{ translateX: "-50%" }}
            className="flex flex-none gap-20 pr-16"
          >
            {[...new Array(2)].fill(0).map((_, index) => (
              <React.Fragment key={index}>
                {logoPartner.map(({ src, alt }) => (
                  <img
                    key={alt}
                    src={src}
                    alt={alt}
                    className="h-16 w-auto flex-none saturate-50"
                  />
                ))}
              </React.Fragment>
            ))}
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Trusted;
