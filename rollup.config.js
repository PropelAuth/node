import commonjs from "@rollup/plugin-commonjs"
import resolve from "@rollup/plugin-node-resolve"
import typescript from "@rollup/plugin-typescript"
import peerDepsExternal from "rollup-plugin-peer-deps-external"

const packageJson = require("./package.json")

const extensions = [".js", ".ts"]

const globals = {
    ...packageJson.devDependencies,
}

export default [
    // Browser and worker supported build
    {
        input: "src/index.ts",
        output: [
            {
                file: packageJson.mainWorker,
                format: "cjs",
                sourcemap: true,
            },
            {
                file: packageJson.moduleWorker,
                format: "esm",
                sourcemap: true,
            },
        ],
        plugins: [
            peerDepsExternal(),
            resolve({
                extensions,
                exportConditions: ["browser", "worker"],
                browser: true,
            }),
            commonjs(),
            typescript(),
        ],
        external: Object.keys(globals),
    },
    // Node build
    {
        input: "src/index.ts",
        output: [
            {
                file: packageJson.main,
                format: "cjs",
                sourcemap: true,
            },
            {
                file: packageJson.module,
                format: "esm",
                sourcemap: true,
            },
        ],
        plugins: [
            peerDepsExternal(),
            resolve({
                extensions,
            }),
            commonjs(),
            typescript(),
        ],
        external: Object.keys(globals),
    },
]
