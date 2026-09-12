import Link from "@docusaurus/Link";

const HomepageHero = () => {
  return (
    <div className="relative z-20 w-full h-screen -mt-(--ifm-navbar-height) pt-(--ifm-navbar-height) bg-white-ish">
      <div className="h-full max-w-3/4 mx-auto grid grid-cols-2">
        <div className="pt-30 flex justify-center">
          <div className="pl-16">
            <h1 className="hero-title pb-6 text-gray-dark">
              Secure Cardano synchronization in{" "}
              <span className="glitch">minutes</span>, not hours
            </h1>
            <p className="pb-6 text-(--ifm-color-primary-darker)">
              Open Source &lt;/&gt; &nbsp;|&nbsp; Community Driven ∞
              &nbsp;|&nbsp; Built for Cardano ✴
            </p>
            <Link
              className="inline-flex items-center gap-2 px-6 py-3 font-bold text-white rounded-lg border-[0.5px] bg-gray-dark hover:no-underline hover:scale-105 transition-all hover:text-white mr-12"
              to="/manual/operate/run-signer-node"
            >
              Become a Signer
              <span className="flex relative size-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-(--ifm-color-primary) opacity-75"></span>
                <span className="relative inline-flex mx-auto my-auto size-2 rounded-full bg-(--ifm-color-primary) opacity-75"></span>
              </span>
            </Link>
            <Link
              className="inline-block gap-2 px-4 py-3 font-bold text-gray-dark rounded-lg border-[0.5px] bg-white hover:no-underline hover:scale-105 transition-all"
              to="/manual/operate/run-signer-node"
            >
              Explore the protocol
            </Link>
          </div>
        </div>
        <div className="content-center">
          <video
            autoPlay
            loop
            muted
            className="block m-auto w-5/8 object-contain"
            preload="auto"
            aria-label="Video Shield Mithril"
          >
            <source src={"mithril-shield.mp4"} type="video/mp4" />
          </video>
        </div>
      </div>
    </div>
  );
};

export default HomepageHero;
