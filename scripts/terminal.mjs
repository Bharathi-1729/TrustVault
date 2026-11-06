import { emitKeypressEvents } from 'node:readline';

export async function hiddenInput(prompt) {
  if (!process.stdin.isTTY) throw new Error('An interactive terminal is required for hidden input.');
  process.stdout.write(prompt);
  emitKeypressEvents(process.stdin);
  const previous = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = () => {
      process.stdin.off('keypress', onKey);
      process.stdin.setRawMode(previous || false);
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onKey = (character, key = {}) => {
      if (key.ctrl && key.name === 'c') { finish(); reject(new Error('Cancelled')); }
      else if (key.name === 'return' || key.name === 'enter') { finish(); resolve(value); }
      else if (key.name === 'backspace') value = [...value].slice(0, -1).join('');
      else if (character && !key.ctrl && !key.meta && !/[\r\n\u001b]/.test(character)) value += character;
    };
    process.stdin.on('keypress', onKey);
  });
}
