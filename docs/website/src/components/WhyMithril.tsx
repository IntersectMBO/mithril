import Link from "@docusaurus/Link";

const WhyMithril = () => {
  return (
    <div className="relative w-full bg-white">
      <div className="justify-items-center py-14">
        <h3>Why Mithril ?</h3>
      </div>
      <div className="max-w-3/5 mx-auto grid grid-cols-2 bg-gray-dark rounded-4xl mb-28 py-16">
        <div className="my-auto">
          <div className="px-16 space-y-8">
            <img src="img/mithril-logo-dark.svg" height="50" width="50" />
            <p className="text-white">
              Built on stake-based threshold multisignatures,{" "}
              <span className="text-(--ifm-color-primary) font-bold">
                Mithril
              </span>{" "}
              lets clients verify Cardano chain data without running a full node
              — ideal for wallets, exchanges, bridges, and any app that needs
              verified chain data with minimal overhead
            </p>
            <Link
              className="inline-block px-4 py-2 font-bold text-gray-dark rounded-lg border-[0.5px] bg-white hover:no-underline hover:scale-105 transition-all"
              to="/manual/operate/run-signer-node"
            >
              Learn more
            </Link>
          </div>
        </div>
        <div className="my-auto">
          <div className="px-18 space-y-8 justify-items-center">
            <div className="shine-card bg-(--ifm-color-primary-darkest)/40 rounded-xl p-5">
              <div className="grid grid-cols-3 gap-4">
                <img
                  className="my-auto"
                  src="img/people.svg"
                  height="50"
                  width="50"
                />
                <p className="my-auto col-span-2 text-white-ish text-xs/4">
                  <span className="font-bold text-lg">250+</span>
                  <br />
                  Active Signers
                </p>
              </div>
            </div>
            <div
              className="shine-card bg-(--ifm-color-primary-darkest)/40 rounded-xl p-5"
              style={{ "--shine-delay": "0.4s" } as React.CSSProperties}
            >
              <div className="grid grid-cols-3 gap-4">
                <img
                  className="my-auto"
                  src="img/safe.svg"
                  height="50"
                  width="50"
                />
                <p className="my-auto col-span-2 text-white-ish text-xs/4">
                  <span className="font-bold text-lg">50M+</span>
                  <br />
                  ADA stake securing
                  <br />
                  the network
                </p>
              </div>
            </div>
            <div
              className="shine-card bg-(--ifm-color-primary-darkest)/40 rounded-xl p-5"
              style={{ "--shine-delay": "0.8s" } as React.CSSProperties}
            >
              <div className="grid grid-cols-3 gap-4">
                <img
                  className="my-auto"
                  src="img/rocket.svg"
                  height="50"
                  width="50"
                />
                <p className="my-auto col-span-2 text-white-ish text-xs/4">
                  <span className="font-bold text-lg">8 min</span>
                  <br />
                  To bootstrap a node
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WhyMithril;
