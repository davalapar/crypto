module.exports = {
  globals: {
    // window: true,
    // document: true,
  },
  parserOptions: {
    ecmaVersion: 2018,
    sourceType: 'module'
  },
  env: {
    browser: true,
    node: true
  },
  extends: ['airbnb', 'airbnb/hooks'],
  plugins: ['jsx-a11y', 'react'],
  rules: {
    /**
     * personal:
     * - https://eslint.org/docs/rules/
     */
    'react/no-array-index-key': 0,
    'max-len': 0,
  }
}