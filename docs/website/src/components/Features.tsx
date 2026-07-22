import React, { FC } from "react";
import { motion } from "framer-motion";
import { FeatureList } from "../../homepage-content/features";
import useMediaQuery from "../hooks/useMediaQuery";
import { forTablet } from "../../helpers/media-queries";

type Props = {
  icon: React.JSX.Element;
  title: string;
  description: string;
  index: number;
};

const Feature: FC<Props> = ({ icon, title, description, index }) => {
  const isTabletUp = useMediaQuery(forTablet);

  return (
    <motion.div
      className="flex flex-col gap-3"
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true }}
      transition={{ duration: 0.35, delay: isTabletUp ? index / 2 : 0.25 }}
      variants={{
        visible: { opacity: 1, y: 0 },
        hidden: { opacity: 0, y: 100 },
      }}
    >
      <div className="inline-flex gap-2 border-b pb-3 border-gray [&>*:first-child]:mt-0.5">
        {icon}
        <h4 className="text-2xl leading-7.5 font-medium text-blue">{title}</h4>
      </div>
      <p className="text-black">{description}</p>
    </motion.div>
  );
};

const Features: FC = () => {
  return (
    <section className="py-20 bg-blue-light">
      <div className="pageContainer">
        <motion.h5
          className="text-base text-black pb-10"
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          transition={{ duration: 0.35, delay: 0.15 }}
          variants={{
            visible: { opacity: 1, y: 0 },
            hidden: { opacity: 0, y: 100 },
          }}
        >
          FEATURES
        </motion.h5>
        <motion.div className="flex flex-col laptop:grid tablet:grid-cols-2 laptop:grid-rows-2 laptop:grid-flow-row  gap-x-26.5 laptop:gap-y-10 tablet:gap-y-14 gap-y-12">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} index={idx} {...props} />
          ))}
        </motion.div>
      </div>
    </section>
  );
};

export default Features;
