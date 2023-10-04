const args = process.argv.slice(2);

export default args.reduce((prev, next, i, orig) => {
    if(!next.startsWith("-")) return prev;

    if(next.startsWith("--")) next = next.replace("--", "");
    else next = next.replace("-", "");

    return {...prev, [next]: orig[i+1] ? orig[i+1] : true};
}, {});