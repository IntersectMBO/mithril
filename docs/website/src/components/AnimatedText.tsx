import React, { FC } from "react";
import { motion } from "framer-motion";

const processText = (children: React.ReactNode): React.ReactNode =>
  React.Children.map(children, (child) => {
    if (typeof child === "string") {
      return child.split(" ").map((word, index) => (
        <span key={index} className="inline-block">
          {word.split("").map((char, charIndex) => (
            <motion.span
              key={charIndex}
              className="inline-flex"
              variants={{
                hidden: { opacity: 0, y: -10, rotate: -2 },
                visible: {
                  opacity: 1,
                  y: 0,
                  rotate: 0,
                  transition: {
                    duration: 0.12,
                    ease: "easeOut",
                  },
                },
              }}
            >
              {char}
              {charIndex === word.length - 1 && (
                <span className="inline-flex">&nbsp;</span>
              )}
            </motion.span>
          ))}
        </span>
      ));
    }

    if (React.isValidElement(child)) {
      //@ts-ignore
      const processedText = processText(child.props.children);
      //@ts-ignore
      return React.cloneElement(child, child.props, processedText);
    }
  });

const AnimatedText: FC = () => {
  return (
    <section className="tablet:component py-24">
      <motion.div
        variants={{
          hidden: {},
          visible: {
            transition: {
              staggerChildren: 0.025,
              delayChildren: 0,
            },
          },
        }}
        initial="hidden"
        whileInView="visible"
        viewport={{
          once: true,
        }}
      >
        {processText(
          <h2 className="animated-text-heading text-blue tablet:tracking-tight tracking-[-0.02rem] tablet:text-center desktop:p-0 pageContainer">
            Choosing Mithril means opting for a scalable, secure, and versatile
            enhancement to the Cardano blockchain
          </h2>,
        )}
      </motion.div>
    </section>
  );
};

export default AnimatedText;
