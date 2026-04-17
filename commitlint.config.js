module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [
      'backend', 'frontend', 'ebpf', 'cli', 'docker', 'ci', 'docs', 'db', 'scripts'
    ]],
  },
};
