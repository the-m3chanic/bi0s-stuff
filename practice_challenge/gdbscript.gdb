r

b *0x0000555555555140
commands
  c
end


b *0x0000555555555070
commands
  c
end

b *0x000055555555510b
commands
  p/c $al
  c
end

b *0x000055555555510e
commands
  set $eflags |= (1 << 6)
  c
end

end
continue

