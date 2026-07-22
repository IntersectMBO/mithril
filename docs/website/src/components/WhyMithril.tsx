import React, { useEffect, useRef } from "react";
import Link from "@docusaurus/Link";
import { WhyMithrilContents } from "../../homepage-content/why-mithril";
import { cx } from "cva";
import useMediaQuery from "../hooks/useMediaQuery";
import { forLargeScreen } from "../../helpers/media-queries";

const WhyMithril = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLDivElement | null)[]>([]);
  const isLargeScreen = useMediaQuery(forLargeScreen);

  useEffect(() => {
    let animationFrameId: number;

    const animate = () => {
      const container = containerRef.current;
      if (!container) return;

      const scrollY = window.scrollY;
      const viewportHeight = window.innerHeight;

      const containerTop = container.offsetTop;
      const containerHeight = container.offsetHeight;
      const scrollProgress =
        (scrollY + viewportHeight - containerTop) /
        (containerHeight + viewportHeight);

      itemRefs.current.forEach((el, index) => {
        if (!el) return;

        const start = 0.07 + index * 0.08;
        const end = start + 0.75;

        let localProgress = (scrollProgress - start) / (end - start);
        localProgress = Math.min(Math.max(localProgress, 0), 1);

        const translateZ = -200 + localProgress * 400;
        const opacity =
          localProgress < 0.5 ? localProgress * 2 : (1 - localProgress) * 2;
        const blur =
          localProgress < 0.5
            ? 5 - localProgress * 10
            : (1 - localProgress) * 100;

        el.style.opacity = `${opacity}`;
        el.style.transform = `translateZ(${translateZ}px)`;
        el.style.filter = `blur(${blur}px)`;
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    animationFrameId = requestAnimationFrame(animate);

    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  return (
    <section className="component bg-blue-light">
      <div className="pageContainer">
        <h5 className="text-base text-black pb-12">
          {WhyMithrilContents.title}
        </h5>

        <div className="flex tablet:flex-row flex-col justify-between gap-6.5 text-primary">
          <div
            className="text-3xl text-center flex justify-center text-blue items-center basis-1/2 stuck-grid flex-col gap-4"
            ref={containerRef}
          >
            {WhyMithrilContents.timeline.map((item, index) => (
              <div
                key={index}
                ref={(el) => (itemRefs.current[index] = el)}
                className={cx(
                  "timeline-grid-item",
                  item === "Basho" && "text-blue-highlight",
                )}
                style={{
                  transformStyle: "preserve-3d",
                  opacity: 0,
                  filter: "blur(5px)",
                  transform: "translateZ(-200px)",
                  alignSelf: [
                    "flex-start",
                    "flex-end",
                    "flex-start",
                    "center",
                    "flex-end",
                  ][index % 5],
                }}
              >
                {item}
              </div>
            ))}
          </div>

          <div className="flex flex-col basis-1/2 gap-10 fade-in delay">
            {WhyMithrilContents.descriptionParagraph.message}
            <Link
              className="inline-block px-4 py-3 font-bold text-sm text-white rounded-lg border-[0.5px] border-gray-border no-underline bg-secondary hover:bg-blue-extralight hover:no-underline hover:text-primary hover:scale-105 transition-all w-fit hover:text-white"
              to="/mithril/beginner/why-use-mithril"
            >
              Learn more
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
};

export default WhyMithril;
