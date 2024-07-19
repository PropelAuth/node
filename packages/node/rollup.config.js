import commonjs from "@rollup/plugin-commonjs"
import resolve from "@rollup/plugin-node-resolve"
import typescript from "@rollup/plugin-typescript"
import peerDepsExternal from "rollup-plugin-peer-deps-external"

const packageJson = require("./package.json")

const extensions = [".js", ".ts"]

const globals = {
    ...packageJson.devDependencies,
}

export default [{
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
        }
    ],
    resolveConfig: {
        extensions,
    },
}, {
    output: {
        exports: "named",
        format: "es",
        file: "dist/browser/index.js",
        sourcemap: true,
    },
    resolveConfig: {
        extensions,
        exportConditions: ["browser", "worker"],
        browser: true,
    },
}].map(config => ({
    input: "src/index.ts",
    output: config.output,
    plugins: [
        peerDepsExternal(),
        resolve(config.resolveConfig),
        commonjs(),
        typescript(),
    ],
    external: Object.keys(globals),
}))
