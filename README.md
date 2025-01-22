# RTMR3 Calculator

Verify that a TEE is running a certain docker-compose file.

## How to verify?

1. Go to https://rtmr3-calculator-qoi0kmi55-michals-projects-57026dc4.vercel.app
2. Paste docker-compose file that your app provider claims to have used
3. Paste other required values produced by the TEE
4. Generate RTMR3 value
5. Get a remote attestation quote from a running app and verify it here: https://proof.t16z.com/
6. Compare RTMR3 field encoded within the quote with the one generated by this calculator. If they match, the app was deployed with the same docker-compose file.

## How to run locally?

Make sure you have [Node.js](https://nodejs.org/en/download) installed.

Clone the [repo](https://github.com/propeller-heads/rtmr3-calculator) and run `npm start`.

Alternatively, just use a simple Python script. Put your values in `./src/rtmr3.py` and run it.

## Where can I check the logic?

The only code that really matters for verification is in `./src/rtmr3.tsx`. Everything else is just stuff needed to make it a web app.

The same logic is also implemented in a cleaner file and easier to understand Python script `./src/rtmr3.py`.
You can also find references to DStack code there.

## See also

- Phala Cloud: https://cloud.phala.network/
- RTMR3 explanation: https://phala.network/posts/truth-of-AI-Agent
- How RTMR3 is calculated on DStack (framework powering Phala Cloud): https://github.com/Dstack-TEE/dstack/blob/master/tdxctl/src/fde_setup.rs#L437
