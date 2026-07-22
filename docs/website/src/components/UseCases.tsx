import React, { FC, useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Link from "@docusaurus/Link";
import { useCases } from "../../homepage-content/use-cases";

const processItems = (items: string[]): React.ReactNode => {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setIndex((prev) => (prev + 1) % items.length);
    }, 2500);

    return () => clearInterval(interval);
  }, []);
  return (
    <AnimatePresence mode="wait">
      <motion.span
        key={index}
        initial={{ opacity: 0, y: 40 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: {
            type: "spring",
            bounce: 0.4,
            duration: 0.2,
            damping: 9,
          },
        }}
        exit={{
          opacity: 0,
          y: -30,
          transition: {
            duration: 0.1,
          },
        }}
        className="absolute pageContainer tablet:max-w-96 tablet:p-0 tablet:ml-2.5 tablet:left-auto left-0 tablet:mt-0 mt-16 use-case-text text-[2.5rem]"
      >
        {items[index]}
      </motion.span>
    </AnimatePresence>
  );
};
const UseCases: FC = () => {
  return (
    <section className="component max-w-[730px] mx-auto">
      <motion.div
        className="flex flex-col tablet:gap-12 gap-28 justify-center"
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
        <h2 className="text-gray-light tablet:ml-6 tablet:text-[2.5rem] text-[2.0625rem] tablet:text-left text-center tablet:tracking-tight tracking-[-0.02063rem] leading-12 relative tablet:p-0 pageContainer">
          {useCases.nonScrollingText}
          {processItems(useCases.scrollingText.items)}
        </h2>
        <Link
          className="w-fit inline-block mt-6 tablet:mt-0 px-4 py-3 font-bold text-sm text-white border-[0.5px] border-gray-light rounded-lg no-underline bg-secondary hover:bg-blue-extralight hover:no-underline hover:scale-105 transition-all hover:text-white self-center"
          to="/mithril/intro"
        >
          Learn more
        </Link>
      </motion.div>
    </section>
  );
};

export default UseCases;
