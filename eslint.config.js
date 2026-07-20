import init from 'eslint-config-metarhia';

export default [
  ...init,
  {
    languageOptions: {
      sourceType: 'module',
    },
  },
];
