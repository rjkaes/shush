declare module "bash-parser" {
  function parse(source: string, options?: Record<string, unknown>): any;
  export default parse;
}
