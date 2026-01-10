const defaultConfig = require('@wordpress/scripts/config/webpack.config');
const path = require('path');

module.exports = {
    ...defaultConfig,
    entry: {
        admin: path.resolve(__dirname, 'assets/src', 'index.js'),
        profile: path.resolve(__dirname, 'assets/src', 'profile.js'),
    },
    output: {
        ...defaultConfig.output,
        path: path.resolve(__dirname, 'build'),
        filename: '[name].js',
    },
    plugins: [
        ...defaultConfig.plugins.map((plugin) => {
            if (plugin.constructor.name === 'MiniCssExtractPlugin') {
                return new plugin.constructor({
                    ...plugin.options,
                    filename: (pathData) => {
                        // Strip './style-' or 'style-' prefix potentially added by wp-scripts
                        const name = pathData.chunk.name.replace(/^(\.\/)?style-/, '');
                        return `${name}.css`;
                    },
                });
            }
            return plugin;
        }),
    ],
};

