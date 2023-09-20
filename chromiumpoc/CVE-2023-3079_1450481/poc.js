function boom() {
  function getargs() {
    return arguments;
  }
  let arr = getargs(1, 2, 3, 45)
  arr.a1 = 6.6
  let arrc = arr;
  a = 'a1';
  for (let i = 0; i < 816; i++) {
    arr[a] = 5.5;
    if (i == 805) {
      arr = [5, 6, 7];
      a = 5;
    }
    if (i == 810) {
      arr = arrc;
      a = 4;
    }
  }
  // TheHole.
  %DebugPrint(arr[5]);
  return arr[5];
}
boom();
