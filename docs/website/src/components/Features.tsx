const Features = () => {
  return (
    <div className="relative w-full bg-white-ish">
      <div className="justify-items-center py-14">
        <h3>Features</h3>
      </div>
      <div className="max-w-3/4 mx-auto grid grid-cols-2  pt-4 pb-14 space-y-8 gap-8">
        <div className="">
          <div className="inline-flex gap-2 border-b pb-3 mb-3 border-(--ifm-color-primary-darker) [&>*:first-child]:mt-0.5">
            %%
            <h4 className="text-xl leading-7.5 m-0">Trustless Light wallets</h4>
          </div>
          <p className="text-black m-0 leading-normal">
            Fully open-source, non-custodial chain state that emphasizes privacy
            and functionality without relying on third-party servers
          </p>
        </div>
        <div className="">
          <div className="inline-flex gap-2 border-b pb-3 mb-3 border-(--ifm-color-primary-darker) [&>*:first-child]:mt-0.5">
            %%
            <h4 className="text-xl leading-7.5 m-0">Succint state proofs</h4>
          </div>
          <p className="text-black m-0 leading-normal">
            Allow participants to verify the validity of a blockchain’s entire
            history or specific state transitions with constant verification
            costs and minimal bandwidth
          </p>
        </div>
        <div className="">
          <div className="inline-flex gap-2 border-b pb-3 mb-3 border-(--ifm-color-primary-darker) [&>*:first-child]:mt-0.5">
            %%
            <h4 className="text-xl leading-7.5 m-0">
              Faster node bootstrapping
            </h4>
          </div>
          <p className="text-black m-0 leading-normal">
            Fast and secure data synchronization with layer 2 solutions –
            including bridges, sidechains, and rollups – as well as applications
            like light wallets.
          </p>
        </div>
        <div className="">
          <div className="inline-flex gap-2 border-b pb-3 mb-3 border-(--ifm-color-primary-darker) [&>*:first-child]:mt-0.5">
            %%
            <h4 className="text-xl leading-7.5 m-0">Decentralization</h4>
          </div>
          <p className="text-black m-0 leading-normal">
            {" "}
            Improved security and transparency, data and transactions are
            recorded on distributed, verifiable ledgers accessible to all
            participants
          </p>
        </div>
      </div>
    </div>
  );
};

export default Features;
