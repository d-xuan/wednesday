using TikzPictures

function hfun_bar(vname)
  val = Meta.parse(vname[1])
  return round(sqrt(val), digits=2)
end

function hfun_m1fill(vname)
  var = vname[1]
  return pagevar("index", var)
end

function lx_baz(com, _)
  # keep this first line
  brace_content = Franklin.content(com.braces[1]) # input string
  # do whatever you want here
  return uppercase(brace_content)
end

function env_tikzcd(e, _)
  content = strip(Franklin.content(e))
  name = strip(Franklin.content(e.braces[1]))
  # save SVG at __site/assets/[path/to/file]/$name.svg
  rpath = joinpath("assets", splitext(Franklin.locvar(:fd_rpath))[1], "$name.svg")
  outpath = joinpath(Franklin.path(:site), rpath)
  # if the directory doesn't exist, create it
  outdir = dirname(outpath)
  isdir(outdir) || mkpath(outdir)
  # save the file and show it
  save(SVG(outpath), TikzPicture(content; environment="tikzcd", preamble="\\usepackage{tikz-cd}"))
  return "@@invert_image\n\\fig{/$(Franklin.unixify(rpath))}@@"
end
